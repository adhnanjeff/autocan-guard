import os
import secrets
import logging
import jwt
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)

# JWT Configuration
# Never hardcode the signing secret: a leaked secret lets anyone forge tokens.
# Read it from the environment; if absent, generate an ephemeral per-process
# secret (tokens won't survive a restart) and warn loudly.
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(64)
    logger.warning(
        "JWT_SECRET not set; using a random per-process secret. "
        "Set the JWT_SECRET environment variable for stable tokens."
    )
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
        """Create default admin and viewer users.

        Passwords come from ADMIN_PASSWORD / VIEWER_PASSWORD env vars. If unset,
        a random password is generated and logged once so no weak, well-known
        default (admin123/viewer123) ever ships. Existing users are left as-is.
        """
        admin_password = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        viewer_password = os.getenv("VIEWER_PASSWORD") or secrets.token_urlsafe(12)
        if not os.getenv("ADMIN_PASSWORD"):
            logger.warning("ADMIN_PASSWORD not set; generated admin password: %s", admin_password)
        if not os.getenv("VIEWER_PASSWORD"):
            logger.warning("VIEWER_PASSWORD not set; generated viewer password: %s", viewer_password)

        users = [
            ("admin", admin_password, "admin"),
            ("viewer", viewer_password, "viewer")
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