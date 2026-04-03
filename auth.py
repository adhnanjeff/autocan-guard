import jwt
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

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
        """Initialize users table"""
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
        """Create default admin and viewer users"""
        users = [
            ("admin", "admin123", "admin"),
            ("viewer", "viewer123", "viewer")
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for username, password, role in users:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, password_hash, role)
                )
        
        conn.commit()
        conn.close()
    
    def authenticate(self, username, password):
        """Authenticate user and return JWT token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        password_hash, role = result
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            # Generate JWT token
            payload = {
                "sub": username,
                "role": role,
                "iss": "autocan-guard",
                "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            return {"token": token, "role": role}
        
        return None
    
    def verify_token(self, token):
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

# Global auth manager instance
auth_manager = AuthManager()

def require_auth(required_role=None):
    """Decorator to require authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Missing or invalid authorization header"}), 401
            
            token = auth_header.split(' ')[1]
            payload = auth_manager.verify_token(token)
            
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            
            # Check role if required
            if required_role and payload.get('role') != required_role:
                return jsonify({"error": "Insufficient permissions"}), 403
            
            # Add user info to request
            request.user = payload
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator