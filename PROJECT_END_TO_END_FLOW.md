# AutoCAN Guard — End-to-End Project Flow

## 1) Project Purpose
AutoCAN Guard is a software-defined vehicle (SDV) security pipeline that:
- Simulates ECU/CAN traffic
- Verifies message authenticity (cryptographic signatures)
- Detects anomalous behavior using multi-layer analysis + ML
- Converts detections into a continuous trust score
- Applies IPS containment policies in real time
- Streams telemetry to Kafka
- Aggregates analytics through ETL and MongoDB
- Exposes observability APIs and dashboards (React/FastAPI/Flask)

---

## 2) High-Level Architecture

```text
ECU Command Inputs / Attack Scripts
              |
              v
      can_generator.py
      (signed CAN frames)
              |
              |  (mock bus + /tmp/*.pkl message exchange)
              v
       can_listener.py
  (verify + detect + trust + policy + IPS)
              |
      +-------+-------------------+------------------+
      |                           |                  |
      v                           v                  v
Vehicle State Engine          Storage Logs        V2V Alerts
(vehicle_state.py)        (JSON/local/S3 paths)   (v2v_*.py)
      |
      +--> React API / FastAPI endpoints
      |
      +--> Kafka telemetry topics
      |
      +--> ETL batching -> MongoDB analytics
```

---

## 3) Core Runtime Components

## Traffic Generation Layer
- `can_generator.py`
  - Produces speed (`0x130`), steering (`0x120`), and brake (`0x140`) messages at ~10 Hz
  - Signs messages with `security/MessageSigner`
  - Publishes telemetry to Kafka via `simple_kafka_producer.py`
  - Ingests raw telemetry into ETL buffers (`etl_pipeline.py`)

## Detection & Control Layer
- `can_listener.py`
  - Consumes CAN messages from mock bus / interface
  - Verifies signatures (`MessageVerifier`)
  - Extracts temporal + behavioral + contextual + physics features
  - Runs ML anomaly detection (`anomaly_detector.py`)
  - Updates trust (`trust_engine.py`)
  - Applies containment (`policy_engine.py`) and IPS limits (`ips_engine.py`)
  - Logs evaluation samples into `evaluation_data/*.jsonl`

## Trust & Policy Layer
- `trust_engine.py`
  - Core trust update model:
  - `Trust(t+1) = Trust(t) + trust_delta`
  - Significant anomaly decay only when anomaly > 0.3
  - Recovery when anomaly < 0.2
- `policy_engine.py`
  - Maps trust to containment actions (`NONE`, `WARNING`, `CLAMP`, `IGNORE`)
- `ips_engine.py`
  - Maps trust to active IPS modes (`OFF`, `SOFT_LIMIT`, `SAFE_MODE`, `CRITICAL`)
  - Enforces speed/steering sanitization

## Streaming + Analytics Layer
- `simple_kafka_producer.py` / `kafka_producer.py`
- `kafka_message_viewer.py` (live terminal viewer)
- `etl_pipeline.py`
  - Batch window: size-based (50) or time-based (10s)
  - Aggregates CAN/security/Kafka metrics
  - Loads to MongoDB (`analytics_db.py`) or JSON fallback

## API + UI Layer
- `react_api.py` (Flask for React dashboard)
- `vehicle_security_api.py` (FastAPI for observability/control APIs)
- `react-app/` (frontend dashboard)

---

## 4) End-to-End Runtime Sequence

## Step 0 — Initialization
1. `start_system.sh` clears stale files:
   - `/tmp/can_messages.pkl`
   - `/tmp/secure_messages.pkl`
   - `/tmp/ecu_commands.pkl`
   - `data/trust_log.json`
2. ETL pipeline starts inside generator (`etl_pipeline.start_pipeline()`)

## Step 1 — Normal Telemetry Creation
1. Generator calculates target speed/steering/brake
2. Builds CAN payload bytes
3. Signs each payload (`MessageSigner`)
4. Sends to mock CAN transport
5. Publishes telemetry to Kafka topic `vehicle.vehicleA.telemetry`

## Step 2 — Ingestion & Verification
1. Listener receives message
2. Decodes CAN ID and values
3. Validates cryptographic integrity/authenticity
4. Updates verified/rejected counters

## Step 3 — Feature Computation
1. Feature extractor computes signal descriptors
2. Temporal extractor computes rate-of-change patterns
3. Context validator checks state consistency
4. Physics validator enforces physical plausibility constraints

## Step 4 — ML & Multi-Layer Anomaly Decision
1. ML model (Isolation Forest) scores anomaly
2. Rule-based/physics/context outputs are combined
3. Startup grace period (`50` messages) suppresses initial transients
4. Decision threshold used for evaluation logging (`anomaly_decision_threshold = 0.5`)

## Step 5 — Trust Update
1. Trust engine receives anomaly/auth/temporal scores
2. Applies weighted decay/recovery
3. Clamps trust score to `[0, 1]`
4. Persists trust state through storage manager

## Step 6 — Policy + IPS Enforcement
1. `policy_engine.py` calculates containment action
2. `ips_engine.py` sets mode based on trust
3. Speed/steering are clamped/sanitized in risky states
4. In critical cases, system runs minimum-safe behavior

## Step 7 — Persist, Stream, and Visualize
1. Security events logged in storage + analytics DB
2. Kafka consumers/UI show live status
3. React/Flask/FastAPI endpoints expose trust, alerts, and history
4. ETL periodically writes aggregated analytics batches

## Step 8 — Evaluation & Reporting
1. Listener writes labeled JSONL samples for experiments
2. Evaluation scripts compute confusion matrix, latency, throughput, variance
3. Graphs exported into `evaluation_reports/`

---

## 5) Trust / Status Thresholds

## Trust Engine Level Labels (`trust_engine.py`)
- `HIGH`: trust > 0.8
- `MEDIUM`: 0.6 < trust <= 0.8
- `LOW`: 0.4 < trust <= 0.6
- `CRITICAL`: trust <= 0.4

## Containment Actions (`policy_engine.py`)
- `NONE`: trust > 0.8
- `WARNING`: 0.6 < trust <= 0.8
- `CLAMP`: 0.4 < trust <= 0.6
- `IGNORE`: trust <= 0.4

## IPS Modes (`ips_engine.py`)
- `OFF`: trust >= 0.8
- `SOFT_LIMIT`: 0.7 <= trust < 0.8
- `SAFE_MODE`: 0.5 <= trust < 0.7
- `CRITICAL`: trust < 0.5

## IPS Limits by Mode
- `SOFT_LIMIT`: speed <= 40 km/h, steering <= ±15°
- `SAFE_MODE`: speed <= 35 km/h, steering <= ±10°
- `CRITICAL`: speed <= 25 km/h, steering <= ±5°

---

## 6) Data Contracts (Key Message Types)

## CAN IDs
- `0x130` → speed
- `0x120` → steering
- `0x140` → brake

## Kafka Topics
- `vehicle.vehicleA.telemetry`
- `vehicle.vehicleA.security`
- `alerts.system`

## ETL Batch Output
- CAN metrics (counts, signed ratio, avg speed/steering/brake)
- Security metrics (event counts, attack rate)
- Kafka metrics (publish success/failure)

---

## 7) Storage Surfaces

## Volatile Runtime Files
- `/tmp/can_messages.pkl`
- `/tmp/secure_messages.pkl`
- `/tmp/ecu_commands.pkl`

## Persistent Local Data
- `data/trust_log.json`
- `evaluation_data/*.jsonl`
- `evaluation_reports/*.png`

## Database
- MongoDB (if available): `canpro_analytics`
  - `security_events`
  - `trust_patterns`
  - `attack_analytics`
  - `etl_batches`

---

## 8) How to Run the Full Flow

## Minimal Security Flow (Core)
1. Terminal 1: `python can_generator.py`
2. Terminal 2: `python can_listener.py`
3. Optional UI: `./start_react_app.sh`

## Kafka Visibility Flow
1. Ensure Kafka broker on `localhost:9092`
2. Start generator: `python can_generator.py`
3. Start live viewer: `./start_kafka_viewer.sh`

## API Observability Flow
1. Start FastAPI: `python vehicle_security_api.py`
2. Use docs at `http://localhost:8000/docs`

---

## 9) Evaluation Flow (Journal/Report)

1. Collect labeled runs in `evaluation_data/`
2. Run evaluation scripts:
   - `evaluation_suite.py`
   - `performance_monitor.py`
3. Generate publication graphs:
   - `generate_1000run_graphs.py`
4. Export figures from `evaluation_reports/` at 300 DPI

---

## 10) Typical Attack-to-Mitigation Lifecycle

1. Attack script injects abnormal values/rates
2. Multi-layer analyzers detect inconsistency
3. Anomaly score rises and trust decays
4. Policy transitions: `NONE -> WARNING -> CLAMP -> IGNORE`
5. IPS transitions: `OFF -> SOFT_LIMIT -> SAFE_MODE -> CRITICAL`
6. Vehicle command space is restricted to safe envelope
7. Alerts and analytics events are logged
8. On recovery (low anomaly), trust gradually rebuilds and IPS exits mode

---

## 11) API Boundary Clarification
`vehicle_security_api.py` provides configuration and observability APIs. The real-time CAN control loop and enforcement occur inside `can_listener.py` + trust/policy/IPS engines. This separation prevents API latency/failure from directly impacting safety logic.

---

## 12) One-Line Project Summary
AutoCAN Guard is an end-to-end SDV cybersecurity testbed that starts from signed CAN telemetry, performs multi-layer real-time detection, computes adaptive trust, enforces safety-constrained IPS policies, and delivers full observability through Kafka, APIs, dashboards, ETL, and analytics reporting.
