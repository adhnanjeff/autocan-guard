import sqlite3
import time
import json
from typing import Dict, Any, Optional

class VehicleDatabase:
    def __init__(self, db_path: str = "vehicle_security.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database with minimal schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS vehicles (
                    vehicle_id TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS trust_state (
                    vehicle_id TEXT PRIMARY KEY,
                    trust_score REAL NOT NULL,
                    ml_enabled INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (vehicle_id) REFERENCES vehicles (vehicle_id)
                );

                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vehicle_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (vehicle_id) REFERENCES vehicles (vehicle_id)
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_vehicle_time 
                ON security_alerts (vehicle_id, timestamp);
            """)

    def register_vehicle(self, vehicle_id: str) -> bool:
        """Register or update vehicle"""
        try:
            current_time = time.time()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO vehicles (vehicle_id, first_seen, last_seen)
                    VALUES (?, 
                        COALESCE((SELECT first_seen FROM vehicles WHERE vehicle_id = ?), ?),
                        ?)
                """, (vehicle_id, vehicle_id, current_time, current_time))
            return True
        except Exception as e:
            print(f"Failed to register vehicle: {e}")
            return False

    def update_trust_state(self, vehicle_id: str, trust_score: float, ml_enabled: bool) -> bool:
        """Update vehicle trust state"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO trust_state 
                    (vehicle_id, trust_score, ml_enabled, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (vehicle_id, trust_score, int(ml_enabled), time.time()))
            return True
        except Exception as e:
            print(f"Failed to update trust state: {e}")
            return False

    def add_security_alert(self, vehicle_id: str, event_type: str, 
                          severity: str, reason: str) -> bool:
        """Add security alert"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO security_alerts 
                    (vehicle_id, event_type, severity, reason, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (vehicle_id, event_type, severity, reason, time.time()))
            return True
        except Exception as e:
            print(f"Failed to add security alert: {e}")
            return False

    def get_vehicle_status(self, vehicle_id: str) -> Optional[Dict[str, Any]]:
        """Get vehicle operational status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get vehicle info
                vehicle = conn.execute(
                    "SELECT * FROM vehicles WHERE vehicle_id = ?", 
                    (vehicle_id,)
                ).fetchone()
                
                if not vehicle:
                    return None
                
                # Get trust state
                trust = conn.execute(
                    "SELECT * FROM trust_state WHERE vehicle_id = ?", 
                    (vehicle_id,)
                ).fetchone()
                
                # Get recent alerts count
                alert_count = conn.execute("""
                    SELECT COUNT(*) as count FROM security_alerts 
                    WHERE vehicle_id = ? AND timestamp > ?
                """, (vehicle_id, time.time() - 3600)).fetchone()
                
                return {
                    'vehicle_id': vehicle['vehicle_id'],
                    'first_seen': vehicle['first_seen'],
                    'last_seen': vehicle['last_seen'],
                    'trust_score': trust['trust_score'] if trust else 1.0,
                    'ml_enabled': bool(trust['ml_enabled']) if trust else True,
                    'trust_updated': trust['updated_at'] if trust else None,
                    'recent_alerts': alert_count['count']
                }
        except Exception as e:
            print(f"Failed to get vehicle status: {e}")
            return None

    def get_fleet_summary(self) -> Dict[str, Any]:
        """Get fleet-wide summary"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Vehicle count
                vehicle_count = conn.execute("SELECT COUNT(*) as count FROM vehicles").fetchone()
                
                # Trust distribution
                trust_dist = conn.execute("""
                    SELECT 
                        CASE 
                            WHEN trust_score > 0.8 THEN 'HIGH'
                            WHEN trust_score > 0.6 THEN 'MEDIUM'
                            WHEN trust_score > 0.4 THEN 'LOW'
                            ELSE 'CRITICAL'
                        END as level,
                        COUNT(*) as count
                    FROM trust_state
                    GROUP BY level
                """).fetchall()
                
                # Recent alerts
                recent_alerts = conn.execute("""
                    SELECT COUNT(*) as count FROM security_alerts 
                    WHERE timestamp > ?
                """, (time.time() - 3600,)).fetchone()
                
                return {
                    'total_vehicles': vehicle_count['count'],
                    'trust_distribution': {row['level']: row['count'] for row in trust_dist},
                    'recent_alerts': recent_alerts['count']
                }
        except Exception as e:
            print(f"Failed to get fleet summary: {e}")
            return {'total_vehicles': 0, 'trust_distribution': {}, 'recent_alerts': 0}