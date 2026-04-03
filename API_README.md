# Vehicle Security API Documentation

## 🎯 API Responsibilities

### ✅ APIs DO:
- Read security state from storage
- Toggle ML mode configuration  
- Expose trust history and alerts
- Provide fleet observability
- Control system configuration

### ❌ APIs DO NOT:
- Send CAN messages
- Modify Kafka streams
- Affect real-time security flow
- Block or filter messages
- Control vehicle directly

## 📡 Endpoints

### Vehicle & Trust
```
GET /vehicles
GET /vehicles/{id}/trust  
GET /vehicles/{id}/alerts
```

### Trust History (Storage Backend Agnostic)
```
GET /vehicles/{id}/trust/history
```
- Automatically uses local files OR S3 objects
- Backend decided by `STORAGE_BACKEND` env var

### ML Toggle (Critical Feature)
```
GET /system/mode
POST /system/mode
```

**Request Body:**
```json
{
  "ml_enabled": true
}
```

**Updates:**
- In-memory API config
- Database state for persistence
- **Note**: Real-time CAN system uses its own trust engine

### System Status
```
GET /system/status
GET /health
```

## 🚀 Usage

**Start API:**
```bash
python vehicle_security_api.py
```

**Test API:**
```bash
python test_api.py
```

**API URL:** http://localhost:8000
**Docs:** http://localhost:8000/docs (FastAPI auto-generated)

## 🔒 Security Boundaries

- **API Layer**: Configuration and observability
- **Real-time Layer**: CAN processing and trust engine
- **Storage Layer**: Data persistence and history
- **Clear separation**: No cross-layer interference