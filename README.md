# Sentinel

Sentinel is an end-to-end intrusion detection and automated incident-response platform built around machine learning, FastAPI, PostgreSQL, n8n, and future threat-intelligence / LLM enrichment.

The project began as a binary network intrusion classifier and is being expanded phase-by-phase into a complete detection, persistence, automation, and response system.

---

## Current Status

| Phase | Description | Status |
|---|---|---|
| 1 | ML Training & Evaluation | âœ… Complete |
| 2 | FastAPI Model Serving | âœ… Complete |
| 3 | PostgreSQL Persistence | âœ… Complete |
| 4 | n8n Automation Foundation | âœ… Complete |
| 5 | FastAPI â†’ n8n Integration | âœ… Complete |
| 6 | Threat Intelligence Enrichment | â³ Next |
| 7 | LLM Incident Analysis | â¬œ Planned |
| 8 | Human Approval & Automated Response | â¬œ Planned |
| 9 | Real-Time Detection System & Dashboard | â¬œ Planned |
| 10 | Full Validation & Deployment Readiness | â¬œ Planned |

---

## What Sentinel Does Today

Sentinel can currently:

- load a trained XGBoost intrusion-detection model
- accept a 77-feature network-flow payload through FastAPI
- classify traffic as `BENIGN` or `ATTACK`
- return attack probability and confidence
- persist detections in PostgreSQL
- preserve the original 77-feature payload as JSONB
- retrieve detection history
- retrieve individual detections by ID
- filter detections by attack status
- automatically trigger a published n8n workflow after prediction
- route ATTACK and BENIGN events through different automation branches
- return the n8n automation result back through FastAPI

---

## Current Architecture

```text
77-Feature Network Input
        â†“
POST /predict
        â†“
FastAPI
        â†“
XGBoost
        â†“
BENIGN / ATTACK
        â†“
PostgreSQL
        â†“
Detection Record
        â†“
FastAPI â†’ n8n Webhook
        â†“
IF attack?
   â†™        â†˜
 TRUE      FALSE
  â†“          â†“
CRITICAL     SAFE
  â†“          â†“
Automation Response
        â†“
FastAPI Response
```

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

### Automation
- n8n
- Webhooks
- Conditional routing
- HTTP integrations

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
BENIGN â†’ 0
ATTACK â†’ 1
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
â”œâ”€â”€ .gitignore
â”œâ”€â”€ README.md
â”‚
â”œâ”€â”€ Dataset/
â”‚   â””â”€â”€ Dataset_README.md
â”‚
â”œâ”€â”€ ML Models/
â”‚   â”œâ”€â”€ CNN/
â”‚   â”‚   â”œâ”€â”€ 04_CICIDS2017_CNN.ipynb
â”‚   â”‚   â”œâ”€â”€ sentinel_cnn_binary_v1_best.keras
â”‚   â”‚   â”œâ”€â”€ sentinel_cnn_scaler_v1.joblib
â”‚   â”‚   â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚   â”‚
â”‚   â”œâ”€â”€ KNN/
â”‚   â”‚   â”œâ”€â”€ 03_CICIDS2017_KNN.ipynb
â”‚   â”‚   â”œâ”€â”€ KNN_README.md
â”‚   â”‚   â”œâ”€â”€ sentinel_knn_scaler_v1.joblib
â”‚   â”‚   â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚   â”‚
â”‚   â”œâ”€â”€ Random Forest/
â”‚   â”‚   â”œâ”€â”€ 01_CICIDS2017_RandomForest.ipynb
â”‚   â”‚   â”œâ”€â”€ README.md
â”‚   â”‚   â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚   â”‚
â”‚   â””â”€â”€ XGBoost/
â”‚       â”œâ”€â”€ 02_CICIDS2017_XGBoost.ipynb
â”‚       â”œâ”€â”€ sentinel_xgboost_binary_v1.json
â”‚       â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app/
â”‚   â”‚   â”œâ”€â”€ main.py
â”‚   â”‚   â”œâ”€â”€ database.py
â”‚   â”‚   â”œâ”€â”€ models.py
â”‚   â”‚   â””â”€â”€ services/
â”‚   â”‚       â””â”€â”€ automation.py
â”‚   â”‚
â”‚   â”œâ”€â”€ test_prediction.py
â”‚   â”œâ”€â”€ test_n8n_connection.py
â”‚   â””â”€â”€ .gitignore
â”‚
â”œâ”€â”€ automation/
â”‚   â””â”€â”€ sentinel_detection_automation.json
â”‚
â””â”€â”€ docs/
    â”œâ”€â”€ Sentinel_Phase_01_ML_Training.md
    â”œâ”€â”€ Sentinel_Phase_02_Model_Serving.md
    â”œâ”€â”€ Sentinel_Phase_03_Database_Persistence.md
    â”œâ”€â”€ Sentinel_Phase_04_n8n_Automation_Foundation.md
    â””â”€â”€ Sentinel_Phase_05_FastAPI_n8n_Integration.md
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
ML Models/Random Forest/README.md
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
```

The detection history endpoint supports:

```text
limit
attack=true
attack=false
```

---

## Example Prediction Response

```json
{
  "detection_id": 2,
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
    "detection_id": 2,
    "model": "XGBoost",
    "confidence": 0.9999658
  }
}
```

---

## n8n Automation

The published automation workflow currently performs:

```text
Webhook
   â†“
IF attack?
 â†™       â†˜
TRUE    FALSE
 â†“        â†“
CRITICAL  SAFE
 â†“        â†“
Respond  Respond
```

The production webhook is configured as:

```text
POST /webhook/sentinel-detection
```

The workflow JSON should be exported into:

```text
automation/sentinel_detection_automation.json
```

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

---

## Roadmap

Upcoming development includes:

### Phase 6 â€” Threat Intelligence Enrichment
Use external security APIs to enrich suspicious detections.

### Phase 7 â€” LLM Incident Analysis
Generate human-readable incident summaries, severity explanations, and recommended actions.

### Phase 8 â€” Human Approval & Automated Response
Add approval / rejection workflows before potentially disruptive actions.

### Phase 9 â€” Real-Time System & Dashboard
Add live traffic/flow ingestion, automatic inference, incident feeds, analytics, and dashboard views.

### Phase 10 â€” Validation & Deployment
Perform end-to-end validation using real benign and attack traffic, service-failure tests, reliability checks, and deployment hardening.

---

## Project Goal

Sentinel is intended to evolve into:

> **An AI-powered network threat detection and automated incident-response platform that combines machine learning, event persistence, automation, external threat intelligence, and human-supervised response workflows.**

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
