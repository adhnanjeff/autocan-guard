from .storage_manager import StorageManager, get_storage_manager
from .base import StorageBackend
from .local_storage import LocalStorage
from .database import VehicleDatabase

# Optional S3 storage (only if boto3 is available)
try:
    from .s3_storage import S3Storage
    __all__ = ['StorageManager', 'get_storage_manager', 'StorageBackend', 'LocalStorage', 'S3Storage', 'VehicleDatabase']
except ImportError:
    S3Storage = None
    __all__ = ['StorageManager', 'get_storage_manager', 'StorageBackend', 'LocalStorage', 'VehicleDatabase']