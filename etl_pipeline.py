import time
import threading
from typing import Dict, Any, List
from datetime import datetime
from collections import deque
import json

class SecurityETLPipeline:
    def __init__(self, vehicle_id: str = "vehicleA"):
        self.vehicle_id = vehicle_id
        self.running = False
        self.etl_thread = None
        
        # Extract: Data buffers (batch collection)
        self.can_messages_buffer = deque(maxlen=1000)
        self.security_events_buffer = deque(maxlen=500)
        self.kafka_telemetry_buffer = deque(maxlen=500)
        
        # Transform: Processing configuration
        self.batch_size = 50
        self.flush_interval = 10.0  # Process every 10 seconds
        self.last_flush = time.time()
        
        # Stats tracking
        self.total_processed = 0
        self.total_batches = 0
        
        print(f"🔄 ETL Pipeline initialized for {vehicle_id}")
    
    def start_pipeline(self):
        """Start ETL processing in background thread"""
        if self.running:
            return
        
        self.running = True
        self.etl_thread = threading.Thread(target=self._etl_loop, daemon=True)
        self.etl_thread.start()
        print("✅ ETL Pipeline started")
    
    def _etl_loop(self):
        """Main ETL processing loop"""
        while self.running:
            try:
                current_time = time.time()
                
                # Check if batch is ready (time-based or size-based)
                messages_ready = len(self.can_messages_buffer) >= self.batch_size
                time_ready = (current_time - self.last_flush) >= self.flush_interval
                
                if messages_ready or time_ready:
                    if self.can_messages_buffer or self.security_events_buffer:
                        self._process_batch()
                        self.last_flush = current_time
                
                time.sleep(1.0)
            except Exception as e:
                print(f"❌ ETL error: {e}")
    
    def _process_batch(self):
        """TRANSFORM and LOAD batch of data"""
        batch_start = time.time()
        
        # Get current buffer sizes
        msg_count = len(self.can_messages_buffer)
        event_count = len(self.security_events_buffer)
        
        print(f"\n🔄 ETL Batch #{self.total_batches + 1}")
        print(f"   📊 Processing: {msg_count} CAN messages, {event_count} security events")
        
        # TRANSFORM: Aggregate security metrics
        transformed_data = self._transform_security_metrics()
        
        # LOAD: Store to analytics database
        self._load_to_analytics_db(transformed_data)
        
        # Update stats
        self.total_processed += msg_count + event_count
        self.total_batches += 1
        
        # Clear buffers
        self.can_messages_buffer.clear()
        self.security_events_buffer.clear()
        self.kafka_telemetry_buffer.clear()
        
        elapsed = time.time() - batch_start
        print(f"   ✅ Batch complete in {elapsed:.2f}s")
        print(f"   📈 Total processed: {self.total_processed} records across {self.total_batches} batches\n")
    
    def _transform_security_metrics(self) -> Dict[str, Any]:
        """TRANSFORM: Convert raw data into analytics"""
        # Initialize metrics structure
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "vehicle_id": self.vehicle_id,
            "batch_id": self.total_batches + 1,
            "can_metrics": self._aggregate_can_data(),
            "security_metrics": self._aggregate_security_data(),
            "kafka_metrics": self._aggregate_kafka_data()
        }
        
        return metrics
    
    def _aggregate_can_data(self) -> Dict[str, Any]:
        """Aggregate CAN message statistics"""
        if not self.can_messages_buffer:
            return {}
        
        # Group by CAN ID
        can_ids = {}
        speeds = []
        steerings = []
        brakes = []
        
        for msg in self.can_messages_buffer:
            can_id = msg.get("can_id", "unknown")
            
            if can_id not in can_ids:
                can_ids[can_id] = {"count": 0, "signed": 0}
            
            can_ids[can_id]["count"] += 1
            if msg.get("signed"):
                can_ids[can_id]["signed"] += 1
            
            # Extract telemetry values
            if can_id == "0x130":  # Speed
                speeds.append(msg.get("value", 0))
            elif can_id == "0x120":  # Steering
                steerings.append(msg.get("value", 0))
            elif can_id == "0x140":  # Brake
                brakes.append(msg.get("value", 0))
        
        return {
            "total_messages": len(self.can_messages_buffer),
            "by_can_id": can_ids,
            "avg_speed": sum(speeds) / len(speeds) if speeds else 0,
            "avg_steering": sum(steerings) / len(steerings) if steerings else 0,
            "avg_brake": sum(brakes) / len(brakes) if brakes else 0
        }
    
    def _aggregate_security_data(self) -> Dict[str, Any]:
        """Aggregate security event statistics"""
        if not self.security_events_buffer:
            return {}
        
        event_types = {}
        attack_count = 0
        
        for event in self.security_events_buffer:
            event_type = event.get("event_type", "unknown")
            
            if event_type not in event_types:
                event_types[event_type] = 0
            event_types[event_type] += 1
            
            if event.get("is_attack"):
                attack_count += 1
        
        return {
            "total_events": len(self.security_events_buffer),
            "by_type": event_types,
            "attack_count": attack_count,
            "attack_rate": attack_count / len(self.security_events_buffer) if self.security_events_buffer else 0
        }
    
    def _aggregate_kafka_data(self) -> Dict[str, Any]:
        """Aggregate Kafka telemetry statistics"""
        if not self.kafka_telemetry_buffer:
            return {}
        
        return {
            "total_published": len(self.kafka_telemetry_buffer),
            "success_count": sum(1 for k in self.kafka_telemetry_buffer if k.get("success")),
            "failed_count": sum(1 for k in self.kafka_telemetry_buffer if not k.get("success"))
        }
    
    def _load_to_analytics_db(self, data: Dict[str, Any]):
        """LOAD: Store transformed data to MongoDB"""
        try:
            # Option 1: Use existing analytics_db
            from analytics_db import analytics_db
            
            # Store batch summary
            analytics_db.db.etl_batches.insert_one({
                "vehicle_id": data["vehicle_id"],
                "batch_id": data["batch_id"],
                "timestamp": data["timestamp"],
                "metrics": data,
                "created_at": datetime.utcnow()
            })
            
            print(f"   💾 Loaded to MongoDB: etl_batches collection")
            
        except ImportError:
            # Option 2: Fallback to JSON file storage
            self._save_to_json(data)
    
    def _save_to_json(self, data: Dict[str, Any]):
        """Fallback: Save to JSON file"""
        import os
        output_dir = "/tmp/etl_output"
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"{output_dir}/batch_{data['batch_id']}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"   💾 Saved to: {filename}")
    
    # EXTRACT: Data ingestion methods
    def ingest_can_message(self, can_id: str, value: float, signed: bool = False):
        """Extract CAN message into buffer"""
        self.can_messages_buffer.append({
            "timestamp": datetime.utcnow().isoformat(),
            "can_id": can_id,
            "value": value,
            "signed": signed
        })
    
    def ingest_security_event(self, event_type: str, details: Dict[str, Any]):
        """Extract security event into buffer"""
        self.security_events_buffer.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "is_attack": event_type in ["injection", "replay", "dos"],
            **details
        })
    
    def ingest_kafka_telemetry(self, can_id: str, success: bool):
        """Extract Kafka publish event"""
        self.kafka_telemetry_buffer.append({
            "timestamp": datetime.utcnow().isoformat(),
            "can_id": can_id,
            "success": success
        })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ETL pipeline statistics"""
        return {
            "running": self.running,
            "total_batches": self.total_batches,
            "total_processed": self.total_processed,
            "current_buffers": {
                "can_messages": len(self.can_messages_buffer),
                "security_events": len(self.security_events_buffer),
                "kafka_telemetry": len(self.kafka_telemetry_buffer)
            },
            "last_flush": datetime.fromtimestamp(self.last_flush).isoformat()
        }
    
    def stop_pipeline(self):
        """Stop ETL pipeline gracefully"""
        print("🔌 Stopping ETL Pipeline...")
        self.running = False
        
        # Process remaining data
        if self.can_messages_buffer or self.security_events_buffer:
            print("   📦 Processing final batch...")
            self._process_batch()
        
        if self.etl_thread:
            self.etl_thread.join(timeout=5.0)
        
        print(f"✅ ETL Pipeline stopped. Processed {self.total_processed} total records")

# Global ETL instance
etl_pipeline = SecurityETLPipeline()