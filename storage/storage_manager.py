import os
from typing import Dict, Any, Optional
from .base import StorageBackend
from .local_storage import LocalStorage
from .database import VehicleDatabase

class StorageManager:
    """Unified storage interface combining backend storage and operational DB"""
    
    def __init__(self, storage_backend: str = "local"):
        # Storage backend for logs/alerts
        if storage_backend == "local":
            self.storage = LocalStorage()
        elif storage_backend == "s3":
            try:
                from .s3_storage import S3Storage
            except ImportError:
                raise ValueError("S3 backend requires 'pip install boto3'")
            bucket = os.getenv('S3_BUCKET_NAME')
            if not bucket:
                raise ValueError("S3_BUCKET_NAME environment variable required")
            self.storage = S3Storage(
                bucket_name=bucket,
                aws_access_key=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region=os.getenv('AWS_REGION', 'us-east-1')
            )
        else:
            raise ValueError(f"Unknown storage backend: {storage_backend}")
        
        # Database for operational state
        self.db = VehicleDatabase()
        
        print(f"✅ Storage initialized: {storage_backend} backend + SQLite DB")

    def log_trust_update(self, vehicle_id: str, trust_score: float, 
                        ml_enabled: bool, anomaly_score: float = 0.0) -> bool:
        """Log trust score update to both storage and DB"""
        # Register vehicle in DB
        self.db.register_vehicle(vehicle_id)
        
        # Update operational state in DB
        self.db.update_trust_state(vehicle_id, trust_score, ml_enabled)
        
        # Store detailed log in storage backend
        log_data = {
            'trust_score': trust_score,
            'ml_enabled': ml_enabled,
            'anomaly_score': anomaly_score
        }
        return self.storage.store_trust_log(vehicle_id, log_data)

    def log_security_alert(self, vehicle_id: str, event_type: str, 
                          severity: str, reason: str, details: Dict[str, Any] = None) -> bool:
        """Log security alert to both storage and DB"""
        # Add to DB for operational queries
        self.db.add_security_alert(vehicle_id, event_type, severity, reason)
        
        # Store detailed alert in storage backend
        alert_data = {
            'event_type': event_type,
            'severity': severity,
            'reason': reason,
            'details': details or {}
        }
        return self.storage.store_alert(vehicle_id, alert_data)

    def get_vehicle_status(self, vehicle_id: str) -> Optional[Dict[str, Any]]:
        """Get vehicle operational status from DB"""
        return self.db.get_vehicle_status(vehicle_id)

    def get_fleet_summary(self) -> Dict[str, Any]:
        """Get fleet-wide summary from DB"""
        return self.db.get_fleet_summary()

    def get_trust_history(self, vehicle_id: str, limit: int = 100) -> list:
        """Get trust history from storage backend"""
        return self.storage.get_trust_history(vehicle_id, limit)

    def get_alerts(self, vehicle_id: str, limit: int = 50) -> list:
        """Get alerts from storage backend"""
        return self.storage.get_alerts(vehicle_id, limit)

# Global storage manager instance
_storage_manager = None

def get_storage_manager() -> StorageManager:
    """Get global storage manager instance"""
    global _storage_manager
    if _storage_manager is None:
        backend = os.getenv('STORAGE_BACKEND', 'local')
        _storage_manager = StorageManager(backend)
    return _storage_manager