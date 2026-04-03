import json
import os
import time
from typing import Dict, Any
from .base import StorageBackend

class LocalStorage(StorageBackend):
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

    def store_trust_log(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store trust log to JSON file"""
        try:
            file_path = os.path.join(self.data_dir, f"{vehicle_id}_trust.json")
            
            # Load existing data
            logs = []
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    logs = json.load(f)
            
            # Add timestamp
            data['timestamp'] = time.time()
            logs.append(data)
            
            # Keep last 1000 entries
            logs = logs[-1000:]
            
            # Save back
            with open(file_path, 'w') as f:
                json.dump(logs, f, indent=2)
            
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