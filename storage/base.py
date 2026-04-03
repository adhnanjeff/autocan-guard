from abc import ABC, abstractmethod
from typing import Dict, Any

class StorageBackend(ABC):
    @abstractmethod
    def store_trust_log(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store trust score log entry"""
        pass

    @abstractmethod
    def store_alert(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store security alert"""
        pass

    @abstractmethod
    def get_trust_history(self, vehicle_id: str, limit: int = 100) -> list:
        """Get trust score history"""
        pass

    @abstractmethod
    def get_alerts(self, vehicle_id: str, limit: int = 50) -> list:
        """Get security alerts"""
        pass