# Sentinel

Sentinel is an end-to-end network intrusion detection and cybersecurity automation platform built with machine learning, FastAPI, PostgreSQL, n8n, threat intelligence, LLM-assisted incident analysis, and a human-in-the-loop analyst dashboard.

The project began as a binary CIC-IDS2017 intrusion classifier and is being expanded phase-by-phase into a complete detection, persistence, enrichment, analysis, approval, response, monitoring, and deployment system.

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
| 7 | LLM Incident Analysis | Complete |
| 8 | Analyst Dashboard + Human Approval & Response | Complete |
| 9 | Real-Time Detection + Live Monitoring & Analytics | Next |
| 10 | Full Validation & Deployment Readiness | Planned |

---

## What Sentinel Does Today

Sentinel can currently:

- load a trained XGBoost intrusion-detection model
- accept a 77-feature network-flow payload through FastAPI
- accept optional network metadata beside the ML feature vector
- classify traffic as `BENIGN` or `ATTACK`
- return attack probability and confidence
- persist detections in PostgreSQL
- store source/destination IPs, ports, protocol, and observation time
- retrieve and filter detection history
- automatically trigger a published n8n workflow after prediction
- route ATTACK and BENIGN events through separate automation branches
- enrich ATTACK events with AbuseIPDB source-IP reputation data
- persist threat-intelligence results back into PostgreSQL
- reject threat enrichment for BENIGN detections
- send enriched ATTACK incidents to Google Gemini for structured analysis
- validate LLM output with Pydantic
- persist LLM provider, model, status, analysis JSONB, errors, and timestamps
- expose incident details through a Next.js analyst dashboard
- support light and dark dashboard themes
- allow an analyst to approve or reject an incident response
- restrict response actions to an explicit allowlist
- execute approved response actions in simulation mode
- persist review and response state back into PostgreSQL
- keep BENIGN traffic on the original SAFE path without calling AbuseIPDB or Gemini

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
                       Threat Enrichment
                                |
                                v
                    Save Threat Intelligence
                                |
                                v
                      LLM Incident Analysis
                                |
                                v
                    Pydantic Validation
                                |
                                v
                      Save LLM Analysis
                                |
                                v
                       Analyst Dashboard
                                |
                                v
                      Human Approve/Reject
                                |
                                v
                  Allowlisted Response Service
                                |
                                v
                    Persist Response Outcome
```

The XGBoost model still receives exactly 77 numeric ML features. Network metadata, threat intelligence, LLM analysis, human review, and response state remain separate layers.

---

## Phase 8 Validation Evidence

### Analyst dashboard

The analyst dashboard displays detection history, ATTACK/BENIGN counts, confidence, model information, and clickable incident records.

![Sentinel analyst dashboard](docs/assets/phase%208/01_analyst_dashboard.png)

### Live threat intelligence and LLM incident analysis

A controlled ATTACK shell was processed through the live n8n production workflow, AbuseIPDB lookup, Gemini analysis, PostgreSQL persistence, and the dashboard. Gemini generated the incident severity from the evidence available to it.

![Live incident analysis](docs/assets/phase%208/02_live_incident_analysis.png)

### Human-controlled response execution

The analyst approved a `LOG_ONLY` action from the dashboard. Sentinel executed the allowlisted response in simulation mode and persisted the completed result.

![Human response execution](docs/assets/phase%208/03_human_response_execution.png)

> Phase 8 validated the live AbuseIPDB -> Gemini -> dashboard -> human approval -> response path. The initial ATTACK state used for this specific controlled test was manually created, so it was not a true 77-feature XGBoost inference test. Full genuine end-to-end traffic validation is reserved for Phase 10.

---

## Phase 8: Analyst Dashboard + Human Approval & Response

Phase 8 introduces a real analyst-facing web application instead of relying on PowerShell, Swagger, and pgAdmin for normal incident handling.

The dashboard is built with:

```text
Next.js
TypeScript
Tailwind CSS
```

It consumes the existing FastAPI backend and does not duplicate backend logic.

The dashboard currently supports:

```text
Detection history
ATTACK / BENIGN summary cards
Attack rate
Clickable incident details
ML detection evidence
Network metadata
AbuseIPDB context
AI incident analysis
Severity badge
Human review state
Response state
Approve / Reject controls
Response-action selection
Analyst notes
Execute Approved Response
Light / Dark mode
```

---

## Human Decision Layer

A completed ATTACK analysis transitions into:

```text
review_status = PENDING
```

The analyst can then:

```text
APPROVE
or
REJECT
```

An approved incident stores:

```text
review_status = APPROVED
response_action = selected action
response_status = PENDING
```

A rejected incident stores:

```text
review_status = REJECTED
response_action = NULL
response_status = NOT_STARTED
```

Response execution is blocked unless:

```text
review_status == APPROVED
```

---

## Response Actions

The current allowlist is:

```text
BLOCK_SOURCE_IP
LOG_ONLY
```

`BLOCK_SOURCE_IP` currently runs in:

```text
SIMULATION
```

mode, so Sentinel validates the full response lifecycle without modifying the host firewall during development.

`LOG_ONLY` records the incident without taking a network action.

The response state can be:

```text
NOT_STARTED
PENDING
EXECUTED
FAILED
```

---

## Technology Stack

### Machine Learning

- Python
- XGBoost
- Random Forest
- K-Nearest Neighbors
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
- Google GenAI SDK

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
- Google Gemini

### Dashboard

- Next.js
- React
- TypeScript
- Tailwind CSS

### Development / Tooling

- Git / GitHub
- Jupyter / Google Colab
- Python virtual environments
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

XGBoost was selected as the production inference model.

Production model:

```text
ML Models/XGBoost/sentinel_xgboost_binary_v1.json
```

---

## Project Structure

```text
Sentinel/
|-- .gitignore
|-- README.MD
|
|-- Dataset/
|   `-- Dataset_README.md
|
|-- ML Models/
|   |-- CNN/
|   |-- KNN/
|   |-- Random Forest/
|   `-- XGBoost/
|
|-- backend/
|   |-- app/
|   |   |-- main.py
|   |   |-- database.py
|   |   |-- models.py
|   |   `-- services/
|   |       |-- automation.py
|   |       |-- llm_analysis.py
|   |       `-- response_service.py
|   |-- test_prediction.py
|   |-- test_n8n_connection.py
|   `-- .gitignore
|
|-- dashboard/
|   |-- app/
|   |   |-- incidents/
|   |   |   `-- [id]/
|   |   |       `-- page.tsx
|   |   |-- layout.tsx
|   |   |-- globals.css
|   |   `-- page.tsx
|   |-- components/
|   |   `-- ThemeToggle.tsx
|   |-- package.json
|   `-- next.config.ts
|
|-- automation/
|   `-- sentinel_detection_automation.json
|
`-- docs/
    |-- assets/
    |   |-- phase 7/
    |   `-- phase 8/
    |-- Sentinel_Phase_01_ML_Training.md
    |-- Sentinel_Phase_02_Model_Serving.md
    |-- Sentinel_Phase_03_Database_Persistence.md
    |-- Sentinel_Phase_04_n8n_Automation_Foundation.md
    |-- Sentinel_Phase_05_FastAPI_n8n_Integration.md
    |-- Sentinel_Phase_06_Threat_Intelligence_Enrichment.md
    |-- Sentinel_Phase_07_LLM_Incident_Analysis.md
    `-- Sentinel_Phase_08_Analyst_Dashboard_Human_Approval_Response.md
```

---

## Environment Variables

Create:

```text
backend/.env
```

with local values:

```env
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_db

N8N_WEBHOOK_URL=http://localhost:5678/webhook/sentinel-detection
GEMINI_API_KEY=your_gemini_key
```

Do not commit `.env`.

The AbuseIPDB API key is stored using n8n Credentials rather than in source code.

---

## Running Sentinel

Start PostgreSQL, then start FastAPI from:

```text
Sentinel/backend
```

with:

```powershell
uvicorn app.main:app --reload
```

FastAPI:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

Start n8n separately:

```powershell
n8n
```

n8n:

```text
http://localhost:5678
```

Start the dashboard from:

```text
Sentinel/dashboard
```

with:

```powershell
npm run dev
```

Dashboard:

```text
http://localhost:3000
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
POST /detections/{detection_id}/analysis
POST /detections/{detection_id}/review
POST /detections/{detection_id}/respond
```

---

## Incident Lifecycle

A normal ATTACK incident now follows:

```text
Detection
   |
   v
Threat Intelligence
   |
   v
LLM Analysis
   |
   v
review_status = PENDING
   |
   v
Analyst Dashboard
   |
   +-- REJECT
   |     |
   |     v
   |  No response
   |
   `-- APPROVE
         |
         v
   response_status = PENDING
         |
         v
   Execute Approved Response
         |
         v
   EXECUTED / FAILED
```

---

## Safety Controls

Sentinel currently enforces:

- BENIGN detections cannot be enriched as threats
- BENIGN detections cannot receive LLM incident analysis
- LLM analysis requires threat intelligence first
- human review requires completed LLM analysis
- response execution requires explicit human approval
- already-reviewed detections cannot be reviewed again
- already-executed responses cannot be executed again
- response actions must belong to a fixed allowlist
- disruptive network actions remain simulated during development

---

## Phase Documentation

Every completed phase has a dedicated technical record under `docs/`.

Completed documentation currently covers Phases 1 through 8.

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

Complete.

### Phase 7 - LLM Incident Analysis

Complete.

### Phase 8 - Analyst Dashboard + Human Approval & Response

Complete. Adds the Next.js analyst dashboard, light/dark mode, incident detail pages, human approval/rejection, allowlisted response actions, persisted response outcomes, and browser-based incident handling.

### Phase 9 - Real-Time Detection + Live Monitoring & Analytics

**Next.** Add real-time flow ingestion, automatic inference, live incident updates, dashboard analytics, charts, service-health indicators, and operational monitoring.

### Phase 10 - Full Validation & Deployment Readiness

Perform genuine end-to-end validation using real benign and attack feature rows, service-failure testing, reliability checks, deployment hardening, final documentation, and release preparation.

---

## Project Goal

Sentinel is intended to evolve into:

> **An AI-powered network threat detection and incident-response platform that combines machine learning, event persistence, threat intelligence, LLM-assisted analysis, automation, a professional analyst dashboard, and human-supervised response workflows.**

---

## Dataset

Sentinel uses the **CIC-IDS2017** dataset published by the Canadian Institute for Cybersecurity, University of New Brunswick.

Official dataset page:

https://www.unb.ca/cic/datasets/ids-2017.html

See:

```text
Dataset/Dataset_README.md
```

for dataset and reproduction notes.

---

## License

A license has not yet been selected.
