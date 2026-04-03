from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from storage import get_storage_manager
from auth import auth_manager, require_auth
import os

app = FastAPI(title="Vehicle Security API", version="1.0.0")
security = HTTPBearer()

# Global storage and system state
storage = get_storage_manager()
_system_state = {"ml_enabled": True}  # In-memory config

class MLModeRequest(BaseModel):
    ml_enabled: bool

class LoginRequest(BaseModel):
    username: str
    password: str

class VehicleInfo(BaseModel):
    vehicle_id: str
    trust_score: float
    ml_enabled: bool
    last_seen: float
    recent_alerts: int

@app.post("/auth/login")
async def login(request: LoginRequest) -> Dict[str, Any]:
    """Authenticate user and return JWT token"""
    result = auth_manager.authenticate(request.username, request.password)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    return result

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    payload = auth_manager.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return payload

def require_admin(user = Depends(verify_token)):
    """Require admin role"""
    if user.get('role') != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user

@app.get("/vehicles")
async def get_vehicles(user = Depends(verify_token)) -> List[VehicleInfo]:
    """Get all vehicles and their status"""
    try:
        fleet_summary = storage.get_fleet_summary()
        vehicles = []
        
        # For demo, return vehicleA status
        vehicle_status = storage.get_vehicle_status("vehicleA")
        if vehicle_status:
            vehicles.append(VehicleInfo(
                vehicle_id=vehicle_status['vehicle_id'],
                trust_score=vehicle_status['trust_score'],
                ml_enabled=vehicle_status['ml_enabled'],
                last_seen=vehicle_status['last_seen'],
                recent_alerts=vehicle_status['recent_alerts']
            ))
        
        return vehicles
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vehicles/{vehicle_id}/trust")
async def get_vehicle_trust(vehicle_id: str, user = Depends(verify_token)) -> Dict[str, Any]:
    """Get vehicle trust status"""
    try:
        status = storage.get_vehicle_status(vehicle_id)
        if not status:
            raise HTTPException(status_code=404, detail="Vehicle not found")
        
        return {
            "vehicle_id": vehicle_id,
            "trust_score": status['trust_score'],
            "ml_enabled": status['ml_enabled'],
            "trust_updated": status['trust_updated'],
            "trust_level": "HIGH" if status['trust_score'] > 0.8 else 
                          "MEDIUM" if status['trust_score'] > 0.6 else
                          "LOW" if status['trust_score'] > 0.4 else "CRITICAL"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vehicles/{vehicle_id}/alerts")
async def get_vehicle_alerts(vehicle_id: str, limit: int = 20, user = Depends(verify_token)) -> List[Dict[str, Any]]:
    """Get vehicle security alerts"""
    try:
        alerts = storage.get_alerts(vehicle_id, limit)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vehicles/{vehicle_id}/trust/history")
async def get_trust_history(vehicle_id: str, limit: int = 100, user = Depends(verify_token)) -> List[Dict[str, Any]]:
    """Get trust score history from storage backend"""
    try:
        history = storage.get_trust_history(vehicle_id, limit)
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/mode")
async def get_system_mode(user = Depends(verify_token)) -> Dict[str, Any]:
    """Get current ML mode"""
    return {
        "ml_enabled": _system_state["ml_enabled"],
        "security_mode": "CRYPTO_PLUS_ML" if _system_state["ml_enabled"] else "CRYPTO_ONLY",
        "storage_backend": os.getenv('STORAGE_BACKEND', 'local')
    }

@app.post("/system/mode")
async def set_system_mode(request: MLModeRequest, user = Depends(require_admin)) -> Dict[str, Any]:
    """Toggle ML mode - CRITICAL: Updates in-memory config only"""
    try:
        # Update in-memory state
        _system_state["ml_enabled"] = request.ml_enabled
        
        # Update DB state for persistence
        storage.db.update_trust_state("vehicleA", 1.0, request.ml_enabled)
        
        # NOTE: Real-time system (CAN listener) reads from its own trust engine
        # This API only controls the global config state
        
        return {
            "ml_enabled": request.ml_enabled,
            "security_mode": "CRYPTO_PLUS_ML" if request.ml_enabled else "CRYPTO_ONLY",
            "message": "ML mode updated in API config. Real-time system uses its own trust engine."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/status")
async def get_system_status(user = Depends(verify_token)) -> Dict[str, Any]:
    """Get overall system status"""
    try:
        fleet_summary = storage.get_fleet_summary()
        return {
            "total_vehicles": fleet_summary['total_vehicles'],
            "trust_distribution": fleet_summary['trust_distribution'],
            "recent_alerts": fleet_summary['recent_alerts'],
            "ml_enabled": _system_state["ml_enabled"],
            "storage_backend": os.getenv('STORAGE_BACKEND', 'local')
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/trust-timeline/{vehicle_id}")
async def get_trust_timeline(vehicle_id: str, hours: int = 24, user = Depends(verify_token)) -> Dict[str, Any]:
    """Get trust timeline data for analytics"""
    try:
        from analytics import SecurityAnalytics
        analytics = SecurityAnalytics()
        
        df = analytics.get_trust_timeline(vehicle_id, hours)
        
        if df.empty:
            return {"data": [], "attack_windows": []}
        
        # Convert to JSON-serializable format
        timeline_data = [
            {
                "timestamp": row['timestamp'],
                "trust_score": row['trust_score'],
                "ml_enabled": row['ml_enabled'],
                "anomaly_score": row.get('anomaly_score', 0.0)
            }
            for _, row in df.iterrows()
        ]
        
        attack_windows = analytics.get_attack_windows(vehicle_id, hours)
        
        return {
            "data": timeline_data,
            "attack_windows": attack_windows
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/ml-comparison/{vehicle_id}")
async def get_ml_comparison(vehicle_id: str, user = Depends(verify_token)) -> Dict[str, Any]:
    """Get ML performance comparison data"""
    try:
        from analytics import SecurityAnalytics
        analytics = SecurityAnalytics()
        
        stats = analytics.get_ml_comparison_stats(vehicle_id)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/alerts/{vehicle_id}")
async def get_alert_analytics(vehicle_id: str, hours: int = 24, user = Depends(verify_token)) -> Dict[str, Any]:
    """Get alert analytics data"""
    try:
        from analytics import SecurityAnalytics
        analytics = SecurityAnalytics()
        
        alert_stats = analytics.get_alert_analytics(vehicle_id, hours)
        return alert_stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analytics/health/{vehicle_id}")
async def get_system_health(vehicle_id: str, user = Depends(verify_token)) -> Dict[str, Any]:
    """Get system health score"""
    try:
        from analytics import SecurityAnalytics
        analytics = SecurityAnalytics()
        
        health_score = analytics.get_system_health_score(vehicle_id)
        return {"health_score": health_score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check() -> Dict[str, str]:
    """API health check"""
    return {"status": "healthy", "service": "vehicle-security-api"}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Vehicle Security API")
    print("📊 Endpoints: /vehicles, /vehicles/{id}/trust, /system/mode")
    print("⚠️  API controls observability only - does not affect real-time CAN flow")
    uvicorn.run(app, host="0.0.0.0", port=8000)