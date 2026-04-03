# Vehicle Digital Twin - Phase 3: Trust-Based Security

A complete vehicle digital twin with **real-time CAN attack detection and containment**. Converts CAN traffic into measured trust, detects attacks using ML, and actively limits unsafe vehicle behavior.

## Architecture

```
CAN Messages → Feature Extraction → Anomaly Detection (ML)
     ↓              ↓                      ↓
Vehicle State ← Containment ← Trust Engine ← Trust Score
     ↓
Digital Twin (risk-aware)
```

## Quick Start

1. **Setup System**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Start Components** (3 terminals)
   ```bash
   # Terminal 1: CAN Generator
   python can_generator.py
   
   # Terminal 2: Digital Twin
   streamlit run digital_twin_app.py
   
   # Terminal 3: Attack Simulator
   python attacks/attack_simulator.py
   ```

## What You'll See

- **🔒 Security Pipeline**: Real-time trust scoring and containment
- **🎯 Attack Detection**: ML-based anomaly detection
- **🛡️ Active Defense**: Steering clamping and message filtering
- **📊 Trust Metrics**: Live trust score and security status
- **2D Vehicle Visualization**: Moving vehicle with risk indicators
- **Real-time Gauges**: Speed and steering with safety limits

## Security Features (Phase 3)

### 🎯 ML Toggle (Demo Feature)
- **🔴 CRYPTO_ONLY Mode**: Messages authenticated, no behavioral analysis
- **🟢 CRYPTO_PLUS_ML Mode**: Crypto + behavioral anomaly detection
- **Demo Purpose**: Shows why ML is essential for insider attack detection
- **Toggle Control**: Real-time switching in UI

### 🔍 Feature Extraction
- **Frequency**: Messages per second
- **Delta**: Value change magnitude  
- **Jitter**: Timing irregularity

### 🤖 Anomaly Detection
- **Model**: Isolation Forest (unsupervised ML)
- **Training**: 50 samples of normal behavior
- **Output**: Anomaly score [0,1]

### 🎯 Trust Engine
- **Formula**: `Trust(t+1) = Trust(t) - α·anomaly - β·(1-auth) - γ·(1-temporal)`
- **Behavior**: Gradual decay, slow recovery
- **Range**: [0,1] continuous trust score

### 🛡️ Runtime Containment
| Trust Level | Action | Effect |
|-------------|--------|---------|
| > 0.8 | None | Normal operation |
| 0.6-0.8 | Warning | Visual indicators |
| 0.4-0.6 | Clamp | Steering ±15°, Speed limit |
| < 0.4 | Ignore | Block malicious messages |

### ⚔️ Attack Simulation
- **Flood**: High-frequency message spam
- **Replay**: Repeated message injection
- **Malicious**: Dangerous steering/speed values

## Files

**Core System:**
- `vehicle_state.py` - Vehicle physics engine
- `can_generator.py` - Realistic CAN message simulation
- `can_listener.py` - CAN processing with security pipeline
- `digital_twin_app.py` - Risk-aware visualization

**Security Pipeline:**
- `feature_extractor.py` - Behavioral signal extraction
- `anomaly_detector.py` - ML-based attack detection
- `trust_engine.py` - Trust score calculation
- `policy_engine.py` - Containment decision logic

**Demo & Testing:**
- `attacks/attack_simulator.py` - CAN attack generation
- `attacks/test_attack.py` - Simple test attacks
- `setup.sh` - System initialization

## Technology Stack

- **CAN**: Linux vcan + python-can
- **ML**: scikit-learn Isolation Forest
- **State Engine**: Python + NumPy
- **Visualization**: Streamlit + Plotly
- **Security**: Real-time trust scoring
- **Update Rate**: 10Hz (industry standard)

## Demo Scenarios

1. **Normal Operation**: Trust stays HIGH, no containment
2. **ML Toggle Demo**: 
   - Toggle ML OFF → run attack → trust stays HIGH (vulnerable)
   - Toggle ML ON → run same attack → trust drops (protected)
3. **Flood Attack**: High frequency → trust drops → clamping
4. **Malicious Values**: Extreme angles → trust critical → ignore
5. **Recovery**: Stop attack → trust slowly recovers

**Industry Impact**: First open-source vehicle digital twin with ML-based CAN security and active containment.