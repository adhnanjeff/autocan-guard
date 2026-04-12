import json
import os
import time
import tempfile
import shutil
from typing import Dict, Any
from .base import StorageBackend

class LocalStorage(StorageBackend):
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

    def store_trust_log(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store trust log to JSON file with atomic write"""
        try:
            file_path = os.path.join(self.data_dir, f"{vehicle_id}_trust.json")
            
            # Load existing data with error recovery
            logs = []
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().strip()
                        if content:
                            logs = json.loads(content)
                except (json.JSONDecodeError, Exception) as e:
                    # Corrupted file - start fresh
                    print(f"Warning: Corrupted trust log, starting fresh: {e}")
                    logs = []
            
            # Ensure logs is a list
            if not isinstance(logs, list):
                logs = []
            
            # Add timestamp
            data['timestamp'] = time.time()
            logs.append(data)
            
            # Keep last 1000 entries
            logs = logs[-1000:]
            
            # Atomic write using temp file
            temp_fd, temp_path = tempfile.mkstemp(dir=self.data_dir, suffix='.tmp')
            try:
                with os.fdopen(temp_fd, 'w') as f:
                    json.dump(logs, f, indent=2)
                shutil.move(temp_path, file_path)
            except:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise
            
            return True
        except Exception as e:
            print(f"Failed to store trust log: {e}")
            return False

    def store_alert(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store alert to JSON file"""
        try:
            file_path = os.path.join(self.data_dir, f"{vehicle_id}_alerts.json")
            
            # Load existing data
            alerts = []
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    alerts = json.load(f)
            
            # Add timestamp and ID
            data['timestamp'] = time.time()
            data['id'] = len(alerts) + 1
            alerts.append(data)
            
            # Keep last 500 alerts
            alerts = alerts[-500:]
            
            # Save back
            with open(file_path, 'w') as f:
                json.dump(alerts, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Failed to store alert: {e}")
            return False

    def get_trust_history(self, vehicle_id: str, limit: int = 100) -> list:
        """Get trust history from JSON file"""
        try:
            file_path = os.path.join(self.data_dir, f"{vehicle_id}_trust.json")
            if not os.path.exists(file_path):
                return []
            
            with open(file_path, 'r') as f:
                logs = json.load(f)
            
            return logs[-limit:]
        except Exception as e:
            print(f"Failed to get trust history: {e}")
            return []

    def get_alerts(self, vehicle_id: str, limit: int = 50) -> list:
        """Get alerts from JSON file"""
        try:
            file_path = os.path.join(self.data_dir, f"{vehicle_id}_alerts.json")
            if not os.path.exists(file_path):
                return []
            
            with open(file_path, 'r') as f:
                alerts = json.load(f)
            
            return alerts[-limit:]
        except Exception as e:
            print(f"Failed to get alerts: {e}")
            return []