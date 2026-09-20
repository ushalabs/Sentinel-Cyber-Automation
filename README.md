# Sentinel

Sentinel is an end-to-end network intrusion detection and cybersecurity automation platform built around machine learning, FastAPI, PostgreSQL, n8n, and external threat intelligence.

The project began as a binary network intrusion classifier and is being expanded phase-by-phase into a complete detection, persistence, enrichment, analysis, and response system.

---

## Current Status

| Phase | Description | Status |
|---|---|---|
| 1 | ML Training & Evaluation | Complete |
| 2 | FastAPI Model Serving | Complete |
| 3 | PostgreSQL Persistence | Complete |
| 4 | n8n Automation Foundation | Complete |
| 5 | FastAPI -> n8n Integration | Complete |
| 6 | Threat Intelligence Enrichment | Complete |
| 7 | LLM Incident Analysis | Next |
| 8 | Human Approval & Automated Response | Planned |
| 9 | Real-Time Detection System & Dashboard | Planned |
| 10 | Full Validation & Deployment Readiness | Planned |

---

## What Sentinel Does Today

Sentinel can currently:

- load a trained XGBoost intrusion-detection model
- accept a 77-feature network-flow payload through FastAPI
- accept optional network metadata alongside the ML feature vector
- classify traffic as `BENIGN` or `ATTACK`
- return attack probability and confidence
- persist detections in PostgreSQL
- preserve the original 77-feature payload as JSONB
- store source/destination IPs, ports, protocol, and observation time
- retrieve detection history
- retrieve individual detections by ID
- filter detections by attack status
- automatically trigger a published n8n workflow after prediction
- route ATTACK and BENIGN events through separate automation branches
- enrich ATTACK detections with AbuseIPDB source-IP reputation data
- persist threat-intelligence results back into PostgreSQL
- prevent threat enrichment from being attached to BENIGN detections
- return an enriched CRITICAL incident response for ATTACK events
- return a SAFE automation response for BENIGN events

---

## Current Architecture

```text
                 Network Flow / Event
                         |
              +----------+----------+
              |                     |
              v                     v
      77 ML Features          Network Metadata
              |              IPs, ports, protocol,
              |                 observed time
              +----------+----------+
                         |
                         v
                      FastAPI
                         |
                         v
                      XGBoost
                         |
                         v
                 BENIGN / ATTACK
                         |
                         v
                    PostgreSQL
                         |
                         v
                        n8n
                         |
                  attack == true?
                    /         \
                  NO           YES
                  |             |
                  v             v
                SAFE      AbuseIPDB Lookup
                                |
                                v
                       Enriched Incident
                                |
                                v
                    Save Threat Intelligence
                                |
                                v
                              FastAPI
                                |
                                v
                           PostgreSQL
                                |
                                v
                    Rich CRITICAL Response
```

The 77-feature XGBoost contract remains unchanged. Network identifiers are handled as metadata and are not fed into the model.

---

## Technology Stack

### Machine Learning
- Python
- XGBoost
- Random Forest
- KNN
- CNN / Keras
- scikit-learn
- NumPy
- Pandas
- Joblib

### Backend
- FastAPI
- Uvicorn
- Pydantic
- httpx

### Database
- PostgreSQL
- SQLAlchemy
- psycopg
- JSONB

### Automation & Threat Intelligence
- n8n
- Webhooks
- Conditional routing
- HTTP integrations
- AbuseIPDB

### Development / Tooling
- Python virtual environments
- Git / GitHub
- Jupyter / Google Colab
- pgAdmin

---

## Machine Learning

Sentinel Phase 1 used the CIC-IDS2017 dataset for binary intrusion detection.

Binary labels:

```text
BENIGN -> 0
ATTACK -> 1
```

The final production feature contract contains **77 numeric network-flow features**.

Four models were trained:

- Random Forest
- XGBoost
- K-Nearest Neighbors
- CNN

XGBoost was selected as the initial production inference model because of its strong held-out performance and low number of missed attacks.

The production model used by the backend is:

```text
ML Models/XGBoost/sentinel_xgboost_binary_v1.json
```

---

## Project Structure

```text
Sentinel/
|-- .gitignore
|-- README.md
|
|-- Dataset/
|   `-- Dataset_README.md
|
|-- ML Models/
|   |-- CNN/
|   |   |-- 04_CICIDS2017_CNN.ipynb
|   |   |-- sentinel_cnn_binary_v1_best.keras
|   |   |-- sentinel_cnn_scaler_v1.joblib
|   |   `-- sentinel_feature_columns_v1.joblib
|   |
|   |-- KNN/
|   |   |-- 03_CICIDS2017_KNN.ipynb
|   |   |-- KNN_README.md
|   |   |-- sentinel_knn_scaler_v1.joblib
|   |   `-- sentinel_feature_columns_v1.joblib
|   |
|   |-- Random Forest/
|   |   |-- 01_CICIDS2017_RandomForest.ipynb
|   |   |-- RandomForest_README.md
|   |   `-- sentinel_feature_columns_v1.joblib
|   |
|   `-- XGBoost/
|       |-- 02_CICIDS2017_XGBoost.ipynb
|       |-- sentinel_xgboost_binary_v1.json
|       `-- sentinel_feature_columns_v1.joblib
|
|-- backend/
|   |-- app/
|   |   |-- main.py
|   |   |-- database.py
|   |   |-- models.py
|   |   `-- services/
|   |       `-- automation.py
|   |
|   |-- test_prediction.py
|   |-- test_n8n_connection.py
|   `-- .gitignore
|
|-- automation/
|   `-- sentinel_detection_automation.json
|
`-- docs/
    |-- Sentinel_Phase_01_ML_Training.md
    |-- Sentinel_Phase_02_Model_Serving.md
    |-- Sentinel_Phase_03_Database_Persistence.md
    |-- Sentinel_Phase_04_n8n_Automation_Foundation.md
    |-- Sentinel_Phase_05_FastAPI_n8n_Integration.md
    `-- Sentinel_Phase_06_Threat_Intelligence_Enrichment.md
```

---

## Important Repository Notes

Some large generated files are intentionally excluded from Git.

### Dataset

The raw CIC-IDS2017 archive is not committed.

Download instructions are available in:

```text
Dataset/Dataset_README.md
```

### KNN Binary

The trained KNN binary is approximately 1 GB and is excluded from Git.

Reproduction instructions are available in:

```text
ML Models/KNN/KNN_README.md
```

### Random Forest Binary

The trained Random Forest binary is roughly 50 MB and is also excluded to keep the repository lightweight.

Reproduction instructions are available in:

```text
ML Models/Random Forest/RandomForest_README.md
```

---

## Backend Setup

### 1. Create a virtual environment

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

Current development dependencies include:

```text
fastapi
uvicorn[standard]
xgboost
scikit-learn
joblib
numpy
pandas
sqlalchemy
psycopg[binary]
python-dotenv
httpx
```

---

## Environment Variables

Create:

```text
backend/.env
```

with your own local values:

```env
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_db

N8N_WEBHOOK_URL=http://localhost:5678/webhook/sentinel-detection
```

Do not commit `.env`.

The AbuseIPDB API key is stored in **n8n Credentials**, not in the repository.

---

## Running the Backend

From:

```text
Sentinel/backend
```

activate the virtual environment and run:

```powershell
uvicorn app.main:app --reload
```

FastAPI will normally be available at:

```text
http://127.0.0.1:8000
```

Interactive API docs:

```text
http://127.0.0.1:8000/docs
```

---

## Main API Endpoints

```http
GET  /
GET  /health
GET  /model-info
POST /predict
GET  /detections
GET  /detections/{detection_id}
POST /detections/{detection_id}/enrichment
```

The detection history endpoint supports:

```text
limit
attack=true
attack=false
```

The enrichment endpoint is used by the n8n ATTACK workflow to persist threat-intelligence results back into the existing detection record.

---

## Prediction Input

Sentinel separates model features from network metadata:

```json
{
  "features": {
    "Protocol": 6,
    "Flow Duration": 12345
  },
  "metadata": {
    "source_ip": "203.0.113.50",
    "destination_ip": "192.168.1.10",
    "source_port": 51542,
    "destination_port": 22,
    "transport_protocol": "TCP",
    "observed_at": "2026-09-20T13:05:00+05:00"
  }
}
```

All 77 required feature names must be supplied for real inference. Metadata is optional and is not passed to XGBoost.

---

## Example BENIGN Prediction Response

```json
{
  "detection_id": 10,
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.999966,
  "attack_probability": 0.000034,
  "threshold": 0.5,
  "model": "XGBoost",
  "created_at": "...",
  "automation_triggered": true,
  "automation_result": {
    "status": "SAFE",
    "message": "Sentinel classified traffic as benign",
    "detection_id": 10,
    "model": "XGBoost",
    "confidence": 0.9999658
  }
}
```

---

## Threat Intelligence Enrichment

ATTACK detections are enriched through AbuseIPDB.

The n8n workflow sends the observed `source_ip` to AbuseIPDB and builds a structured incident containing fields such as:

```text
abuse_confidence_score
is_whitelisted
country
isp
domain
usage_type
total_reports
last_reported_at
```

Threat intelligence is persisted using:

```text
threat_provider
threat_intelligence (JSONB)
enriched_at
```

Using JSONB keeps Sentinel flexible enough to add more threat-intelligence providers later without redesigning the database for every provider field.

A backend safety guard rejects enrichment attempts for BENIGN detections.

---

## n8n Automation

The published automation workflow currently performs:

```text
Webhook
   |
   v
IF attack?
   |
   +-- FALSE --> Prepare Benign Result --> Respond SAFE
   |
   `-- TRUE
         |
         v
      Check Source IP Reputation
         |
         v
      Prepare Attack Alert
         |
         v
      Save Threat Intelligence
         |
         v
      Respond with Enriched CRITICAL Incident
```

The production webhook is configured as:

```text
POST /webhook/sentinel-detection
```

The workflow JSON is exported into:

```text
automation/sentinel_detection_automation.json
```

The AbuseIPDB credential itself is not stored in the exported repository workflow.

---

## Phase Documentation

Each completed phase has its own technical record under:

```text
docs/
```

These documents explain:

- objectives
- architecture
- implementation steps
- files created / modified
- tests performed
- problems encountered
- concepts learned
- transition to the next phase

Completed documentation currently covers Phases 1 through 6.

---

## Roadmap

### Phase 1 - ML Training & Evaluation
Complete.

### Phase 2 - FastAPI Model Serving
Complete.

### Phase 3 - PostgreSQL Persistence
Complete.

### Phase 4 - n8n Automation Foundation
Complete.

### Phase 5 - FastAPI to n8n Integration
Complete.

### Phase 6 - Threat Intelligence Enrichment
Complete. Adds network metadata, AbuseIPDB reputation checks, enriched incidents, and PostgreSQL threat-intelligence persistence.

### Phase 7 - LLM Incident Analysis
**Next.** Generate human-readable incident summaries, severity explanations, contextual reasoning, and recommended actions from enriched incidents.

### Phase 8 - Human Approval & Automated Response
Add approval / rejection workflows before potentially disruptive actions.

### Phase 9 - Real-Time System & Dashboard
Add live traffic/flow ingestion, automatic inference, incident feeds, analytics, and dashboard views.

### Phase 10 - Full Validation & Deployment Readiness
Perform end-to-end validation using real benign and attack traffic, service-failure tests, reliability checks, and deployment hardening.

---

## Project Goal

Sentinel is intended to evolve into:

> **An AI-powered network threat detection and automated incident-response platform that combines machine learning, event persistence, threat intelligence, LLM-assisted analysis, automation, and human-supervised response workflows.**

---

## Dataset

Sentinel uses the **CIC-IDS2017** dataset published by the Canadian Institute for Cybersecurity, University of New Brunswick.

Official dataset page:

https://www.unb.ca/cic/datasets/ids-2017.html

See `Dataset/Dataset_README.md` for details.

---

## License

A license has not yet been selected for this project.

Before public release, choose an appropriate license based on whether Sentinel will remain portfolio-only, open source, or evolve into a commercial product.
