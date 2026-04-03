import boto3
import json
import time
from typing import Dict, Any
from .base import StorageBackend

class S3Storage(StorageBackend):
    def __init__(self, bucket_name: str, aws_access_key: str = None, 
                 aws_secret_key: str = None, region: str = 'us-east-1'):
        self.bucket_name = bucket_name
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )

    def store_trust_log(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store ONLY critical trust events to S3 (not every update)"""
        try:
            # ONLY store if trust drops below critical threshold or ML toggle changes
            trust_score = data.get('trust_score', 1.0)
            ml_enabled = data.get('ml_enabled', True)
            
            # Skip normal high-trust updates to save S3 costs
            if trust_score > 0.8 and ml_enabled:
                return True  # Skip but return success
            
            key = f"critical_events/{vehicle_id}/{int(time.time())}.json"
            data['timestamp'] = time.time()
            data['event_type'] = 'critical_trust_event'
            
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json.dumps(data),
                ContentType='application/json'
            )
            return True
        except Exception as e:
            print(f"S3 critical event failed: {e}")
            return False

    def store_alert(self, vehicle_id: str, data: Dict[str, Any]) -> bool:
        """Store ONLY HIGH/CRITICAL alerts to S3"""
        try:
            severity = data.get('severity', 'LOW')
            
            # ONLY store HIGH or CRITICAL alerts to save S3 costs
            if severity not in ['HIGH', 'CRITICAL']:
                return True  # Skip but return success
            
            key = f"critical_alerts/{vehicle_id}/{int(time.time())}.json"
            data['timestamp'] = time.time()
            
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json.dumps(data),
                ContentType='application/json'
            )
            return True
        except Exception as e:
            print(f"S3 critical alert failed: {e}")
            return False

    def get_trust_history(self, vehicle_id: str, limit: int = 100) -> list:
        """Get critical trust events from S3"""
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"critical_events/{vehicle_id}/",
                MaxKeys=limit
            )
            
            events = []
            for obj in response.get('Contents', [])[-limit:]:
                content = self.s3_client.get_object(
                    Bucket=self.bucket_name, 
                    Key=obj['Key']
                )
                events.append(json.loads(content['Body'].read()))
            
            return events
        except Exception as e:
            print(f"S3 critical events failed: {e}")
            return []

    def get_alerts(self, vehicle_id: str, limit: int = 50) -> list:
        """Get critical alerts from S3"""
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=f"critical_alerts/{vehicle_id}/",
                MaxKeys=limit
            )
            
            alerts = []
            for obj in response.get('Contents', [])[-limit:]:
                content = self.s3_client.get_object(
                    Bucket=self.bucket_name, 
                    Key=obj['Key']
                )
                alerts.append(json.loads(content['Body'].read()))
            
            return alerts
        except Exception as e:
            print(f"S3 critical alerts failed: {e}")
            return []