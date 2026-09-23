# Sentinel

Sentinel is an end-to-end network intrusion detection and cybersecurity automation platform built with machine learning, live network-flow collection, FastAPI, PostgreSQL, WebSockets, n8n, threat intelligence, LLM-assisted incident analysis, and a human-in-the-loop Security Operations dashboard.

The project began as a binary CIC-IDS2017 intrusion classifier and has evolved phase-by-phase into a live detection, persistence, enrichment, analysis, approval, response, monitoring, and validation system.

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
| 9 | Real-Time Detection + Live Monitoring & Analytics | Complete |
| 10 | Full Validation & Deployment Readiness | Next |

---

## What Sentinel Does Today

Sentinel can currently:

- capture real IPv4 TCP/UDP traffic from a Windows network interface
- group packets into bidirectional network flows
- calculate the production 77-feature CICFlow-style model vector
- validate feature count, order, and numeric finiteness before inference
- automatically submit completed flows to FastAPI
- classify flows as `BENIGN` or `ATTACK` with XGBoost
- return attack probability and confidence
- persist live detections in PostgreSQL
- store optional network metadata beside the ML feature vector
- broadcast live detection events over WebSockets
- update the dashboard without manual refresh
- show 24-hour ATTACK/BENIGN activity
- show severity distribution
- show top targeted ports
- show top ATTACK source IPs
- monitor FastAPI, PostgreSQL, XGBoost, n8n, and Collector status
- track the Collector through heartbeat messages
- route BENIGN detections directly to persistence/dashboard without n8n
- route ATTACK detections into the published n8n workflow
- enrich ATTACK events with AbuseIPDB
- persist threat intelligence back into PostgreSQL
- analyze enriched ATTACK incidents with Google Gemini
- validate and persist structured LLM analysis
- pin ATTACK incidents in a sticky Analyst Queue until human review
- expose complete incident detail pages
- support light and dark dashboard themes
- allow an analyst to approve or reject an incident
- restrict response actions to an explicit allowlist
- execute approved responses in simulation mode
- persist review and response state
- replay genuine CIC-IDS2017 ATTACK feature rows through the full detection and automation path

---

## Current Architecture

```text
                    LIVE NETWORK TRAFFIC
                            |
                            v
                    Windows Ethernet
                            |
                            v
                      Npcap + Scapy
                            |
                            v
                    Sentinel Collector
                            |
                 CICFlow-style 77 features
                            |
                            v
                         FastAPI
                            |
                            v
                         XGBoost
                            |
                 +----------+----------+
                 |                     |
                 v                     v
              BENIGN                ATTACK
                 |                     |
                 v                     v
            PostgreSQL            PostgreSQL
                 |                     |
                 v                     v
            WebSocket                  n8n
                 |                     |
                 v                     v
             Dashboard             AbuseIPDB
                                       |
                                       v
                              Threat Intelligence
                                       |
                                       v
                                Gemini Analysis
                                       |
                                       v
                                Analyst Queue
                                       |
                                       v
                                Human Review
                                  /       \
                             REJECT     APPROVE
                                          |
                                          v
                              Allowlisted Response
```

The XGBoost model still receives exactly **77 numeric ML features**. Network metadata, threat intelligence, LLM analysis, human review, and response state remain separate layers.

---

## Phase 9 Validation Evidence

### Genuine ATTACK replay through the full automation chain

A genuine CIC-IDS2017 DDoS feature row was replayed through Sentinel. XGBoost classified it as ATTACK, n8n executed, AbuseIPDB enrichment completed, Gemini analysis completed, and the incident entered human review.

![Controlled genuine DDoS replay](docs/assets/phase%209/Complete%20Architecture%20flow.png)

> The ML features are genuine CIC-IDS2017 DDoS features. The `no-metadata` Parquet file does not contain source/destination metadata, so controlled metadata was supplied only for the threat-intelligence/automation portion of the test.

### Final ATTACK-only n8n workflow

Phase 9 simplified automation so BENIGN detections no longer enter n8n. n8n is now dedicated to ATTACK enrichment and analysis.

![Finalized n8n workflow](docs/assets/phase%209/Finalized%20n8n%20structure.png)

### Live dashboard and Analyst Queue

The dashboard now includes live analytics, system health, recent detections, and a sticky Analyst Queue that keeps actionable ATTACK incidents visible until human review.

![Phase 9 Security Operations dashboard](docs/assets/phase%209/New%20Dashboard.png)

---

## Phase 9: Real-Time Detection + Live Monitoring & Analytics

Phase 9 adds the operational layer required for continuous monitoring.

The live path is:

```text
Packet Capture
→ Flow Grouping
→ 77 Features
→ XGBoost
→ PostgreSQL
→ WebSocket
→ Dashboard
```

For BENIGN:

```text
BENIGN
→ PostgreSQL
→ Dashboard
→ stop
```

For ATTACK:

```text
ATTACK
→ PostgreSQL
→ n8n
→ AbuseIPDB
→ Gemini
→ Analyst Queue
→ Human Review
```

---

## Live Collector

The Collector runs as a separate Python process under:

```text
collector/
```

It uses:

```text
Npcap
Scapy
```

to observe live Windows traffic.

The Collector:

- captures TCP/UDP packets
- groups packets into bidirectional flows
- computes the 77 saved features
- validates the feature vector
- submits completed flows to `/predict`
- sends periodic heartbeat messages to FastAPI

The Collector does not load the production XGBoost model directly.

---

## 77-Feature Model Contract

The production feature list is stored at:

```text
ML Models/XGBoost/sentinel_feature_columns_v1.joblib
```

The production model is:

```text
ML Models/XGBoost/sentinel_xgboost_binary_v1.json
```

Before inference, the live feature extractor verifies:

```text
77/77 features
correct feature order
finite numeric values
```

This protects the model from silently receiving malformed live input.

---

## Live Event Streaming

FastAPI exposes:

```text
/ws/events
```

The backend broadcasts events including:

```text
DETECTION_CREATED
THREAT_INTELLIGENCE_UPDATED
ANALYSIS_COMPLETED
REVIEW_UPDATED
RESPONSE_UPDATED
```

The main dashboard and incident detail pages react to these events and refresh live.

---

## Dashboard Analytics

The Phase 9 dashboard includes:

```text
Total Detections
Attacks
Benign
Attack Rate
Pending Review
Critical Incidents
24-hour Detection Activity
Severity Distribution
Top Targeted Ports
Top Source IPs
System Status
Recent Detections
Analyst Queue
```

The Analyst Queue separates high-priority human work from the much higher-volume Recent Detections stream.

---

## Analyst Queue

Actionable ATTACK incidents remain pinned until human review.

Queue states include:

```text
ANALYZING
PENDING REVIEW
ANALYSIS FAILED
```

The queue displays:

```text
Incident ID
Source IP / Port
Severity
Confidence
Protocol
Review / analysis state
```

After the analyst approves or rejects the incident, it leaves the queue.

Historical non-actionable test records remain in PostgreSQL for audit/history but are excluded from the analyst workload.

---

## System Health

FastAPI exposes:

```text
GET /system/status
```

The dashboard monitors:

```text
FastAPI
PostgreSQL
XGBoost
n8n
Collector
```

Collector state is driven by:

```text
POST /collector/heartbeat
```

and can be:

```text
NOT_STARTED
RUNNING
OFFLINE
```

The dashboard polls health periodically so service-state changes do not require a page refresh.

---

## Automation

n8n now receives only ATTACK detections.

Final workflow:

```text
Webhook
→ Check Source IP Reputation
→ Prepare Attack Alert
→ Save Threat Intelligence
→ Analyze Incident with LLM
→ Respond to Webhook
```

BENIGN detections do not consume n8n, AbuseIPDB, or Gemini processing.

---

## Genuine ATTACK Replay

The local CIC-IDS2017 data includes Parquet files such as:

```text
Dataset/CIC-IDS2017/DDoS-Friday-no-metadata.parquet
```

The replay tool can:

```text
load a genuine labeled ATTACK row
→ map the row to the saved 77-feature contract
→ call /predict
→ trigger ATTACK automation
```

A DDoS sample produced:

```text
XGBoost prediction : ATTACK
Confidence         : ~0.999999
Attack probability : ~0.999999
```

The full automation path then completed through AbuseIPDB and Gemini and moved the incident into `PENDING` human review.

---

## Validation Boundary

Phase 9 validated:

### Real live benign traffic

```text
real packet capture
→ live feature extraction
→ XGBoost
→ BENIGN
→ PostgreSQL
→ WebSocket
→ Dashboard
```

### Genuine attack feature replay

```text
genuine CIC-IDS2017 ATTACK feature row
→ XGBoost ATTACK
→ n8n
→ AbuseIPDB
→ Gemini
→ Analyst Queue
```

The ATTACK replay uses genuine stored feature rows rather than a live malicious packet capture.

Phase 10 will perform deeper feature-parity, replay, resilience, and failure validation.

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

### Live Collection

- Npcap
- Scapy
- Python threading
- CICFlow-style flow aggregation

### Backend

- FastAPI
- Uvicorn
- Pydantic
- SQLAlchemy
- httpx
- WebSockets
- Google GenAI SDK

### Database

- PostgreSQL
- psycopg
- JSONB

### Automation & Threat Intelligence

- n8n
- Webhooks
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

## Project Structure

```text
Sentinel/
|-- .gitignore
|-- README.md
|
|-- Dataset/
|   |-- Dataset_README.md
|   `-- CIC-IDS2017/
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
|   |       |-- live_events.py
|   |       |-- llm_analysis.py
|   |       `-- response_service.py
|   |-- test_prediction.py
|   `-- .gitignore
|
|-- collector/
|   |-- collector.py
|   `-- replay_attack.py
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
|   `-- package.json
|
|-- automation/
|   `-- sentinel_detection_automation.json
|
`-- docs/
    |-- assets/
    |   |-- phase 7/
    |   |-- phase 8/
    |   `-- phase 9/
    |-- Sentinel_Phase_01_ML_Training.md
    |-- Sentinel_Phase_02_Model_Serving.md
    |-- Sentinel_Phase_03_Database_Persistence.md
    |-- Sentinel_Phase_04_n8n_Automation_Foundation.md
    |-- Sentinel_Phase_05_FastAPI_n8n_Integration.md
    |-- Sentinel_Phase_06_Threat_Intelligence_Enrichment.md
    |-- Sentinel_Phase_07_LLM_Incident_Analysis.md
    |-- Sentinel_Phase_08_Analyst_Dashboard_Human_Approval_Response.md
    `-- Sentinel_Phase_09_Real_Time_Detection_Live_Monitoring_Analytics.md
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

### 1. PostgreSQL

Start the local PostgreSQL service/database.

### 2. FastAPI

```powershell
cd backend
.\venv\Scripts\Activate.ps1
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

### 3. n8n

```powershell
n8n
```

n8n:

```text
http://localhost:5678
```

### 4. Dashboard

```powershell
cd dashboard
npm run dev
```

Dashboard:

```text
http://localhost:3000
```

### 5. Collector

Run from the Python environment that contains Scapy:

```powershell
cd backend
.\venv\Scripts\Activate.ps1

cd ..\collector
python collector.py
```

The Collector requires Npcap on Windows.

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

GET  /dashboard/stats
GET  /dashboard/activity
GET  /dashboard/severity
GET  /dashboard/top-ports
GET  /dashboard/top-sources
GET  /dashboard/attention

GET  /system/status
POST /collector/heartbeat

WS   /ws/events
```

---

## Incident Lifecycle

```text
Live Flow
   |
   v
XGBoost
   |
   +---------------- BENIGN
   |                    |
   |                    v
   |               DB + Dashboard
   |
   `---------------- ATTACK
                        |
                        v
                       n8n
                        |
                        v
                    AbuseIPDB
                        |
                        v
                  Gemini Analysis
                        |
                        v
                review_status=PENDING
                        |
                        v
                   Analyst Queue
                        |
               +--------+--------+
               |                 |
               v                 v
             REJECT            APPROVE
                                 |
                                 v
                        response_status=PENDING
                                 |
                                 v
                         Execute Response
                                 |
                                 v
                         EXECUTED / FAILED
```

---

## Safety Controls

Sentinel currently enforces:

- the production XGBoost input remains exactly 77 numeric features
- metadata stays outside the ML vector
- malformed/non-finite live feature vectors are rejected
- BENIGN detections do not enter n8n
- BENIGN detections cannot receive threat enrichment
- LLM analysis requires threat intelligence
- human review requires completed LLM analysis
- response execution requires explicit human approval
- response actions belong to a fixed allowlist
- completed responses cannot be executed twice
- actual disruptive firewall blocking remains simulated
- `.env` and credentials remain outside source control

---

## Phase Documentation

Every completed phase has a dedicated technical record under `docs/`.

Completed documentation currently covers **Phases 1 through 9**.

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

Complete. Adds incident detail pages, human approval/rejection, allowlisted response actions, persisted response outcomes, and browser-based incident handling.

### Phase 9 - Real-Time Detection + Live Monitoring & Analytics

Complete. Adds live Windows traffic collection, bidirectional flow construction, CICFlow-style 77-feature extraction, automatic XGBoost inference, WebSocket streaming, operational analytics, system health, ATTACK-only automation routing, an Analyst Queue, and genuine ATTACK replay validation.

### Phase 10 - Full Validation & Deployment Readiness

**Next.** Perform deeper feature-parity testing, multi-sample BENIGN/ATTACK replay, service-failure testing, retry/reconnect validation, reliability checks, deployment hardening, final security review, final documentation, and release preparation.

---

## Project Goal

Sentinel is intended to evolve into:

> **An AI-assisted network threat detection and incident-response platform that combines live network monitoring, machine learning, event persistence, threat intelligence, LLM-assisted analysis, automation, a professional analyst dashboard, and human-supervised response workflows.**

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
